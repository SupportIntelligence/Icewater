
rule n3e9_529b33a9c8800912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.529b33a9c8800912"
     cluster="n3e9.529b33a9c8800912"
     cluster_size="3"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="dealply malicious cloud"
     md5_hashes="['70b421f13a9efa55fd8ebd8967bf06a4','a0dfb3e7a92e8f13d954b3c263e734b9','d116baa2d762c462b186700c3e87484a']"

   strings:
      $hex_string = { 00720063006800050041007000720069006c0003004d006100790004004a0075006e00650004004a0075006c0079000600410075006700750073007400090053 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
