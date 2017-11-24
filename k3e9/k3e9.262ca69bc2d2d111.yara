
rule k3e9_262ca69bc2d2d111
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.262ca69bc2d2d111"
     cluster="k3e9.262ca69bc2d2d111"
     cluster_size="7"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="qukart berbew peed"
     md5_hashes="['1a7a020bcd24180e380f16eecf32e7bc','a00c2e884968b25d06e7e107d2077fc6','b33c8444cdecf833fa446f60fb6c83a4']"

   strings:
      $hex_string = { 636573734100000000930257616974466f7253696e676c654f626a65637400000097025769646543686172546f4d756c746942797465000000980257696e4578 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
