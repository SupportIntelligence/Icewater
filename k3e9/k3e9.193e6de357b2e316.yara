
rule k3e9_193e6de357b2e316
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.193e6de357b2e316"
     cluster="k3e9.193e6de357b2e316"
     cluster_size="29"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="installcore unwanted malicious"
     md5_hashes="['10ecfdd92c7bc227e2de71dcf9df060e','14a2e30ee1fcf3df185c13e5ef019224','8cc047264373769ea196af1e20ac64c6']"

   strings:
      $hex_string = { 04c0f101cd4cd0ec15f864f0583da84ecac48f53e5de0d054a7e3ff921b17941bfdd02eaf4a327932692a5ad5ed3884336aff71c03ffa0e9742fe05fe67b3457 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
