
rule m3e9_7854c369ccab6b16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.7854c369ccab6b16"
     cluster="m3e9.7854c369ccab6b16"
     cluster_size="73"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171111"
     license = "RIL-1.0 [Rick's Internet License] "
     family="vobfus chinky diple"
     md5_hashes="['01d5c80ca2db94c138a1eb290cfd8943','06a05cb51a14fa4528443ba7313a7b3c','8dff4e40dd7b1938cb1a92344a21df3f']"

   strings:
      $hex_string = { 355afdff681ce44200eb178d45bc508d45cc508d45dc506a03e8595bfdff83c410c3c38b4df064890d000000005f5e5bc9c20400558bec515168a63c400064a1 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
