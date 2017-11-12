
rule n3e9_231696c9cc000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.231696c9cc000b32"
     cluster="n3e9.231696c9cc000b32"
     cluster_size="15061"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171111"
     license = "RIL-1.0 [Rick's Internet License] "
     family="kazy injector backdoor"
     md5_hashes="['002100b663ca1445448bbe40f5042d06','0025a2a091ad9fca4a569cc53918dc80','009797c102d9bf76c9a4e661161af069']"

   strings:
      $hex_string = { 101459a6d6568f260cceeccf34d75d705b7b9cb1327288e1a0a3c6658dfd8e3a7a0a919bc31d4f3d39080e3c0d7de6b8250016ade493586fe76dcc54e2b91a1f }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
