
rule m3e9_36c66a48c0000b14
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.36c66a48c0000b14"
     cluster="m3e9.36c66a48c0000b14"
     cluster_size="77"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virut virtob malicious"
     md5_hashes="['05d4f8930beebaf4b7afc954c4d5dae2','0b81d2af66f24ce5b10ff5ac1f4d2958','76db52bc66a823d17ef9d1073df69969']"

   strings:
      $hex_string = { 4fea627bafaa19c82b37252dbe65a1128a250f63a3f7541cf921c9d615f352ac6e433207fd8217f8e5676c0d51f6bdf152c7bde7c430fc203109881d95291a4d }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
