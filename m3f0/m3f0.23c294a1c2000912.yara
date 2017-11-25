
rule m3f0_23c294a1c2000912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3f0.23c294a1c2000912"
     cluster="m3f0.23c294a1c2000912"
     cluster_size="57"
     filetype = "PE32 executable (GUI) Intel 80386 (stripped to external PDB)"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171121"
     license = "RIL-1.0 [Rick's Internet License] "
     family="bitcoinminer coinminer malicious"
     md5_hashes="['04ec567647843ecbea0f2d5a75ee64f7','098b7691bd9852cfe04095918c12ebf1','42ccf22a1ed7e1e342ce58807690399c']"

   strings:
      $hex_string = { 456f1da53574320e49cd3b5d96d8d000084366e9def0621520b2a4f2ae4072faea50be3352a99d2be2e081dd9cba342eb0737789b138c6ceb2c4dac1fe117a37 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
