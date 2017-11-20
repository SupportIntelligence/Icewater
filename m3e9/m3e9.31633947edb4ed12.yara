
rule m3e9_31633947edb4ed12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.31633947edb4ed12"
     cluster="m3e9.31633947edb4ed12"
     cluster_size="17"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171119"
     license = "RIL-1.0 [Rick's Internet License] "
     family="otwycal wapomi vjadtre"
     md5_hashes="['5948ce887cb0eb93fe1ca457e9cfcb54','a064761071d323249dabba1eaa57af34','d76e81f4537c7b9360bf571f9b781117']"

   strings:
      $hex_string = { d2923dfad6975eebb5a7b1f074b6f1fd54b2f9ff479bedff3a85e9ff316be4ff2956d8ff2d4fc6f8727dadaeecd3b776d1995cffce944effca8e3efec89035f3 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
