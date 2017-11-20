
rule m2377_211d6a48c0000912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2377.211d6a48c0000912"
     cluster="m2377.211d6a48c0000912"
     cluster_size="18"
     filetype = "HTML document"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit html script"
     md5_hashes="['01ca65d085892456d72a210f385f65bf','1d1c617a72e90a244d77c8ea145a6ffe','a0e708e13fe9d67c4374e5de8a38375d']"

   strings:
      $hex_string = { c25be35ef173289ada150bca6ee5bc9e4e7d436d05e9dfce49dbc59db287f2cb6555f78c0d351688a26c7e809b66330410f51e926a987a0ae7142af3af00b7ac }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
