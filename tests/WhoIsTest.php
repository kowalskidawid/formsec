<?php

namespace Tests;

use FormSec\Checker;
use PHPUnit\Framework\TestCase;

class WhoIsTest extends TestCase
{
    public function test_request_ip()
    {
        $checker = new Checker('... secure message ...', '54.38.138.126');
        $checker->check();
        $this->assertEquals(90, $checker->score);
    }
}