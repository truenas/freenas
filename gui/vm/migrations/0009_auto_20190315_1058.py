# -*- coding: utf-8 -*-
# Generated by Django 1.10.8 on 2019-03-15 10:58
from __future__ import unicode_literals

from django.db import migrations, models
from pipes import quote


def migrate_rancher_to_grub(apps, schemaeditor):

    VM = apps.get_model('vm', 'vm')
    Volume = apps.get_model('storage', 'volume')

    # Getting the first volume is a compromise to ease the migration.
    # It wont work if the user has multiple pools and VM does not live in first one.
    volume = Volume.objects.order_by('id')[0]

    for vm in VM.objects.filter(vm_type='Container Provider'):
        password = 'docker'
        for device in vm.device_set.filter(dtype='RAW'):
            if 'rootpwd' in device.attributes:
                password = quote(device.attributes.pop('rootpwd'))
                device.save()
                break
        vm.grubconfig = f'/mnt/{volume.vol_name}/.bhyve_containers/configs/{vm.id}_{vm.name}/grub/grub.cfg'
        vm.save()


class Migration(migrations.Migration):

    dependencies = [
        ('vm', '0008_vm_time'),
    ]

    operations = [
        migrations.AddField(
            model_name='vm',
            name='grubconfig',
            field=models.TextField(help_text='Grub.cfg file to be used on boot.', null=True, verbose_name='Grub Config'),
        ),
        migrations.RunPython(
            migrate_rancher_to_grub, reverse_code=migrations.RunPython.noop,
        ),
        migrations.RemoveField(
            model_name='vm',
            name='vm_type',
        ),
        migrations.AlterField(
            model_name='vm',
            name='bootloader',
            field=models.CharField(choices=[('UEFI', 'UEFI'), ('UEFI_CSM', 'UEFI-CSM'), ('GRUB', 'Grub')], default='UEFI', help_text='System boot method and architecture.', max_length=50, verbose_name='Boot Method'),
        ),
    ]
