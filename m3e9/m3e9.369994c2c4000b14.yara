
rule m3e9_369994c2c4000b14
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.369994c2c4000b14"
     cluster="m3e9.369994c2c4000b14"
     cluster_size="16"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="chir runouce virut"
     md5_hashes="['a34c426666da8d2bd76dc6e1a2204788','a40f806d9b05026ce92e4965b541b030','f2a440f427e48178c0f479e4e6ff2f53']"

   strings:
      $hex_string = { 4fea627bafaa19c82b37252dbe65a1128a250f63a3f7541cf921c9d615f352ac6e433207fd8217f8e5676c0d51f6bdf152c7bde7c430fc203109881d95291a4d }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
