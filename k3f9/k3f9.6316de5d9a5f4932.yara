
rule k3f9_6316de5d9a5f4932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3f9.6316de5d9a5f4932"
     cluster="k3f9.6316de5d9a5f4932"
     cluster_size="9"
     filetype = "MS-DOS executable"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="sirefef backdoor malicious"
     md5_hashes="['189a5509917b7da24d542624e91c6fff','2a0a450bdbc703d4bab7055a94ad964b','ef2eabdd16718b4143cbeaa078a31c4b']"

   strings:
      $hex_string = { 2b3a244266a83ba64abaa52e0bd71fdd83a01a0fe78babcf118ca300805f48a19230185f8d73c2cf1195c800805f48a192e0a9609d7a33d011bd880000c082e6 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
