
rule k3e9_2d1491d9ca210b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.2d1491d9ca210b32"
     cluster="k3e9.2d1491d9ca210b32"
     cluster_size="232"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171121"
     license = "RIL-1.0 [Rick's Internet License] "
     family="zbot awkxpwp wemosis"
     md5_hashes="['0252b6678479dc23dc12af5ca1531f8e','033568c4fa748a0eb5c4ffdf878a8a96','16ca79aea352a4c6b836b17aa014daa6']"

   strings:
      $hex_string = { c7f9443e098256ed9c3e0d2ce34b6184d89214fd350c651d157cd5019b4e058121401046fd08966a10f810586f549cde6ebc9e39114c6750667cd5f1cf31c63a }

   condition:
      
      filesize > 16777216 and filesize < 67108864
      and $hex_string
}
