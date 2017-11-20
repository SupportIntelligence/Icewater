
rule m3e9_3d30c4aa0d6bcb12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.3d30c4aa0d6bcb12"
     cluster="m3e9.3d30c4aa0d6bcb12"
     cluster_size="14"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="expiro kakavex blpei"
     md5_hashes="['843ed3eb6527993ed382b3305cfad801','ad6af0b939ae1f0c22c995f45a875409','fa9809a0c2a8eb2e8940b49960be493c']"

   strings:
      $hex_string = { 400096d7d4d5d2d3d0d1dedfdcdddadbd8d9c6c7c4c5c2c3c0c1cecfccf7f4f5f2f3f0f1fefffcfdfafbf8f9e6e7e4e5e2e3e0e1eeefeca6a7a4a5a2a3a0a1ae }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
