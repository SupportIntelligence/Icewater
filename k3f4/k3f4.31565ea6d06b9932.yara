
rule k3f4_31565ea6d06b9932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3f4.31565ea6d06b9932"
     cluster="k3f4.31565ea6d06b9932"
     cluster_size="11"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="malicious asvcs engine"
     md5_hashes="['04ff65d8d5f1d1b05b098e4f679c748a','15e25abbcade0fba85dc31775f302689','fff3e7216ab1aaa90307c75295a834c2']"

   strings:
      $hex_string = { 2fd2d1e2c0a01835290f0dfed5230094c5402e5c59c4c6e616aedf4e632393c78ddb69ac67b7707d6a55cee3e0a8791050b98f209bc9f266033253f75dd7067c }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
