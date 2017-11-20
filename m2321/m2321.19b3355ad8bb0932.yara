
rule m2321_19b3355ad8bb0932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.19b3355ad8bb0932"
     cluster="m2321.19b3355ad8bb0932"
     cluster_size="18"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="backdoor elzob zusy"
     md5_hashes="['0455f09511c3490913adaadc29640028','237b58dc006d8d5250e23a60e803cc03','ec09bc25b19dad9bccba00706bf90ab6']"

   strings:
      $hex_string = { 7b4ed2b50f187ab604e072da21a9e120edcd30f82eaa1f6a7ddbbbd0a0fad376125cc2debb80b4aef258d4d90b9c1a43b02a7555f602c779d8d7073c168d34ca }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
