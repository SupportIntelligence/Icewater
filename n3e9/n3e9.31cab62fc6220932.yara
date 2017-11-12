
rule n3e9_31cab62fc6220932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.31cab62fc6220932"
     cluster="n3e9.31cab62fc6220932"
     cluster_size="12"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171109"
     license = "RIL-1.0 [Rick's Internet License] "
     family="zusy cuegoe malicious"
     md5_hashes="['a5c05b6fee5b52b009214f2fb99cadfe','a907c5d0957249bb702a6c2db8d19471','f434d8b8452290e0590bad4a777b3dbb']"

   strings:
      $hex_string = { 91c176c4c24d183198266d3721bdba4a47026a05dbe803264dc5f00d0118a9f3bc565b4d165a93c1c817a051fd05a8aef6b2ff1f00d2ebb51dc8e2576472455c }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
