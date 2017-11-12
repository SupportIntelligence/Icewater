
rule m3ec_45b7a849c0000932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3ec.45b7a849c0000932"
     cluster="m3ec.45b7a849c0000932"
     cluster_size="90"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171111"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virtob patched virut"
     md5_hashes="['05aa3c072fae0e17c802d79a51a2e887','06ca8d6104f6476e16ac78c88e6965a1','4a078dc4a566b240c3e39beccf2cd4be']"

   strings:
      $hex_string = { d9c1e902756c8807474b75fa5b5e8b4424085fc3891783c7044974afbafffefe7e8b0603d083f0ff33c28b1683c604a90001018174de84d2742c84f6741ef7c2 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
