
rule m3e9_5256968be6600b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.5256968be6600b12"
     cluster="m3e9.5256968be6600b12"
     cluster_size="7382"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="vobfus symmi vbkrypt"
     md5_hashes="['0021c53dac04453f94b13499fd8afdbd','0044aa75df32336992368784d5a256e4','01fc03253d3b5f543ef2c011fc99569e']"

   strings:
      $hex_string = { 45c8508d4dcc518d55d0528d45d4506a08ff158011400083c424c745fc1e000000e82a6dfeffff15581040006817db4100eb3f8b4df083e10485c974098d4ddc }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
