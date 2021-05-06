import itertools
import markdown
import os
import yaml

from catalog_validation.utils import VALID_TRAIN_REGEX
from pkg_resources import parse_version

from middlewared.schema import Bool, Dict, Str
from middlewared.service import accepts, private, Service, ValidationErrors


ITEM_KEYS = ['icon_url']


class CatalogService(Service):

    class Config:
        cli_namespace = 'app.catalog'

    @accepts(
        Str('label'),
        Dict(
            'options',
            Bool('cache', default=True),
        )
    )
    def items(self, label, options):
        """
        Retrieve item details for `label` catalog.

        `options.cache` is a boolean which when set will try to get items details for `label` catalog from cache
        if available.
        """
        catalog = self.middleware.call_sync('catalog.get_instance', label)

        if options['cache'] and self.middleware.call_sync('cache.has_key', f'catalog_{label}_train_details'):
            cached_data = self.middleware.call_sync('cache.get', f'catalog_{label}_train_details')
            questions_context = self.middleware.call_sync('catalog.get_normalised_questions_context')
            for train in cached_data:
                for catalog_item in cached_data[train]:
                    for version in cached_data[train][catalog_item]['versions']:
                        version_data = cached_data[train][catalog_item]['versions'][version]
                        if not version_data.get('healthy'):
                            continue
                        self.normalise_questions(version_data, questions_context)
            return cached_data
        elif not os.path.exists(catalog['location']):
            self.middleware.call_sync('catalog.update_git_repository', catalog, True)

        self.middleware.call_sync('alert.oneshot_delete', 'CatalogNotHealthy', label)

        trains = self.get_trains(catalog['location'], {'alert': True, 'label': label})

        self.middleware.call_sync('cache.put', f'catalog_{label}_train_details', trains, 86400)
        if label == self.middleware.call_sync('catalog.official_catalog_label'):
            # Update feature map cache whenever official catalog is updated
            self.middleware.call_sync('catalog.get_feature_map', False)

        return trains

    @private
    def get_trains(self, location, options=None):
        # We make sure we do not dive into library and docs folders and not consider those a train
        # This allows us to use these folders for placing helm library charts and docs respectively
        trains = {'charts': {}, 'test': {}}
        options = options or {}
        questions_context = self.middleware.call_sync('catalog.get_normalised_questions_context')
        unhealthy_apps = set()
        for train in os.listdir(location):
            if (
                not os.path.isdir(os.path.join(location, train)) or train.startswith('.') or 
                train in ('library', 'docs') or not VALID_TRAIN_REGEX.match(train)
            ):
                continue

            trains[train] = {}

        for train in filter(lambda c: os.path.exists(os.path.join(location, c)), trains):
            category_path = os.path.join(location, train)
            for item in filter(lambda p: os.path.isdir(os.path.join(category_path, p)), os.listdir(category_path)):
                item_location = os.path.join(category_path, item)
                if (not os.path.isdir(item_location) or train.startswith('.')):
                    continue
                trains[train][item] = item_data = {
                    'name': item,
                    'categories': [],
                    'app_readme': None,
                    'location': item_location,
                    'healthy': False,  # healthy means that each version the item hosts is valid and healthy
                    'healthy_error': None,  # An error string explaining why the item is not healthy
                    'versions': {},
                }

                schema = f'{train}.{item}'
                try:
                    self.middleware.call_sync('catalog.validate_catalog_item', item_location, schema, False)
                except ValidationErrors as verrors:
                    item_data['healthy_error'] = f'Following error(s) were found with {item!r}:\n'
                    for verror in verrors:
                        item_data['healthy_error'] += f'{verror[0]}: {verror[1]}'

                    unhealthy_apps.add(f'{item} ({train} train)')
                    # If the item format is not valid - there is no point descending any further into versions
                    continue

                item_data.update(self.item_details(item_location, schema, questions_context))
                unhealthy_versions = []
                for k, v in sorted(item_data['versions'].items(), key=lambda v: parse_version(v[0]), reverse=True):
                    if not item_data['app_readme'] and v['healthy']:
                        item_data['app_readme'] = v['app_readme']
                    elif not v['healthy']:
                        unhealthy_versions.append(k)

                if unhealthy_versions:
                    unhealthy_apps.add(f'{item} ({train} train)')
                    item_data['healthy_error'] = f'Errors were found with {", ".join(unhealthy_versions)} version(s)'
                else:
                    item_data['healthy'] = True

        if options.get('alert') and options.get('label') and unhealthy_apps:
            self.middleware.call_sync(
                'alert.oneshot_create', 'CatalogNotHealthy', {
                    'catalog': options['label'], 'apps': ', '.join(unhealthy_apps)
                }
            )

        return trains

    @private
    def item_details(self, item_path, schema, questions_context):
        # Each directory under item path represents a version of the item and we need to retrieve details
        # for each version available under the item
        item_data = {'versions': {}}
        with open(os.path.join(item_path, 'item.yaml'), 'r') as f:
            item_data.update(yaml.safe_load(f.read()))

        item_data.update({k: item_data.get(k) for k in ITEM_KEYS})

        for version in sorted(
            filter(lambda p: os.path.isdir(os.path.join(item_path, p)), os.listdir(item_path)),
            reverse=True, key=parse_version,
        ):
            item_data['versions'][version] = version_details = {
                'healthy': False,
                'supported': False,
                'healthy_error': None,
                'location': os.path.join(item_path, version),
                'required_features': [],
                'human_version': version,
                'version': version,
            }
            try:
                self.middleware.call_sync(
                    'catalog.validate_catalog_item_version', version_details['location'], f'{schema}.{version}'
                )
            except ValidationErrors as verrors:
                version_details['healthy_error'] = f'Following error(s) were found with {schema}.{version!r}:\n'
                for verror in verrors:
                    version_details['healthy_error'] += f'{verror[0]}: {verror[1]}'

                # There is no point in trying to see what questions etc the version has as it's invalid
                continue

            version_details.update({
                'healthy': True,
                **self.item_version_details(version_details['location'], questions_context)
            })

        return item_data

    @private
    def item_version_details(self, version_path, questions_context=None):
        if not questions_context:
            questions_context = self.middleware.call_sync('catalog.get_normalised_questions_context')
        version_data = {'location': version_path, 'required_features': set()}
        for key, filename, parser in (
            ('chart_metadata', 'Chart.yaml', yaml.safe_load),
            ('schema', 'questions.yaml', yaml.safe_load),
            ('app_readme', 'app-readme.md', markdown.markdown),
            ('detailed_readme', 'README.md', markdown.markdown),
            ('changelog', 'CHANGELOG.md', markdown.markdown),
        ):
            if os.path.exists(os.path.join(version_path, filename)):
                with open(os.path.join(version_path, filename), 'r') as f:
                    version_data[key] = parser(f.read())
            else:
                version_data[key] = None

        # We will normalise questions now so that if they have any references, we render them accordingly
        # like a field referring to available interfaces on the system
        self.normalise_questions(version_data, questions_context)

        version_data['supported'] = self.middleware.call_sync('catalog.version_supported', version_data)
        version_data['required_features'] = list(version_data['required_features'])
        version_data['values'] = self.middleware.call_sync(
            'chart.release.construct_schema_for_item_version', version_data, {}, False
        )['new_values']
        chart_metadata = version_data['chart_metadata']
        if chart_metadata['name'] != 'ix-chart' and chart_metadata.get('appVersion'):
            version_data['human_version'] = f'{chart_metadata["appVersion"]}_{chart_metadata["version"]}'

        return version_data

    @private
    async def get_normalised_questions_context(self):
        return {
            'nic_choices': await self.middleware.call('chart.release.nic_choices'),
            'gpus': await self.middleware.call('k8s.gpu.available_gpus'),
            'timezones': await self.middleware.call('system.general.timezone_choices'),
            'node_ip': await self.middleware.call('kubernetes.node_ip'),
            'certificates': await self.middleware.call('chart.release.certificate_choices'),
            'certificate_authorities': await self.middleware.call('chart.release.certificate_authority_choices'),
            'system.general.config': await self.middleware.call('system.general.config'),
        }

    @private
    def normalise_questions(self, version_data, context):
        version_data['required_features'] = set()
        for question in version_data['schema']['questions']:
            self._normalise_question(question, version_data, context)
        version_data['required_features'] = list(version_data['required_features'])

    def _normalise_question(self, question, version_data, context):
        schema = question['schema']
        for attr in itertools.chain(*[schema.get(k, []) for k in ('attrs', 'items', 'subquestions')]):
            self._normalise_question(attr, version_data, context)

        if '$ref' not in schema:
            return

        data = {}
        for ref in schema['$ref']:
            version_data['required_features'].add(ref)
            if ref == 'definitions/interface':
                data['enum'] = [
                    {'value': i, 'description': f'{i!r} Interface'} for i in context['nic_choices']
                ]
            elif ref == 'definitions/gpuConfiguration':
                data['attrs'] = []
                for gpu, quantity in context['gpus'].items():
                    data['attrs'].append({
                        'variable': gpu,
                        'label': f'GPU Resource ({gpu})',
                        'description': 'Please enter the number of GPUs to allocate',
                        'schema': {
                            'type': 'int',
                            'max': int(quantity),
                            'enum': [
                                {'value': i, 'description': f'Allocate {i!r} {gpu} GPU'}
                                for i in range(int(quantity) + 1)
                            ],
                            'default': 0,
                        }
                    })
            elif ref == 'definitions/timezone':
                data.update({
                    'enum': [{'value': t, 'description': f'{t!r} timezone'} for t in context['timezones']],
                    'default': context['system.general.config']['timezone']
                })
            elif ref == 'definitions/nodeIP':
                data['default'] = context['node_ip']
            elif ref == 'definitions/certificate':
                data.update({
                    'enum': [{'value': None, 'description': 'No Certificate'}] + [
                        {'value': i['id'], 'description': f'{i["name"]!r} Certificate'}
                        for i in context['certificates']
                    ],
                    'default': None,
                    'null': True,
                })
            elif ref == 'definitions/certificateAuthority':
                data.update({
                    'enum': [{'value': None, 'description': 'No Certificate Authority'}] + [
                        {'value': i['id'], 'description': f'{i["name"]!r} Certificate Authority'}
                        for i in context['certificate_authorities']
                    ],
                    'default': None,
                    'null': True,
                })

        schema.update(data)
