<?php

namespace Tests;

use FormSec\Checker;
use PHPUnit\Framework\TestCase;

class CertAlertListTest extends TestCase
{
    public function test_domain_is_on_list()
    {
        $checker = new Checker('... qajuzay.com ...', '54.38.138.126');
        $checker->check();
        $this->assertEquals(70, $checker->score);
    }

    public function test_url_is_on_list()
    {
        $checker = new Checker('... https://qajuzay.com/sad ...', '54.38.138.126');
        $checker->check();
        $this->assertEquals(70, $checker->score);
    }
}