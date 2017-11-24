
rule k3e9_6b1f15e9c8800b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.6b1f15e9c8800b12"
     cluster="k3e9.6b1f15e9c8800b12"
     cluster_size="6"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="waski upatre ipatre"
     md5_hashes="['543e77eeeea8da38b3970da0e70c8c5e','631c89c3f4ce459014a1e217061d6082','f10905f6909222c1a8b26006598c0f52']"

   strings:
      $hex_string = { e5cc3ad2eb2c62d1002a0b915f8cb446ce8f11c8a9a6b1f4a0a4140d55286b85b71fd64a2680dc814288ba0f6d1636b68d82ce926c383da81d61e11cf0739aab }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
