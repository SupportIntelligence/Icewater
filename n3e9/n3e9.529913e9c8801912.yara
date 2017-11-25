
rule n3e9_529913e9c8801912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.529913e9c8801912"
     cluster="n3e9.529913e9c8801912"
     cluster_size="3"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="graftor dealply malicious"
     md5_hashes="['04594b8c2df3783b22666bc46ce37ac4','a80b2bca1c97f4d88b34e3aa592cfb38','f8b3ff2c45402f330a0a64cc21ee52cd']"

   strings:
      $hex_string = { 00720063006800050041007000720069006c0003004d006100790004004a0075006e00650004004a0075006c0079000600410075006700750073007400090053 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
