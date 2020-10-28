[![Build Status](https://travis-ci.org/Darkbat91/centbasic.svg?branch=v1)](https://travis-ci.org/Darkbat91/centbasic)

# Basic Centos Configuration

This role just fills some basic configuration and upate management.

## Default

    * Locks SSH access down to a non root user and passess basic security measures
    * Configures a few basic aliases
    * Updates all packages on the system
        * Does not by default restart the machine if the kernel updates
    * configures yumcron to apply automatic Updates

## Configuration

Two optional settings are

    * allow_reboot - Will permit the system to reboot when this playbook is ran if it is necessary
    * schedule_update_reboot - Will enable a cronjob to run and check if a reboot is neccessary and reboot the machine


## Tags

Each of these systems are also tagged so only parts of the playbook can run across many systems

## Changelog
The [changelog](./CHANGELOG.md) is stored externally
