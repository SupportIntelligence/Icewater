
rule m3e9_6134b4a0d1bb0916
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.6134b4a0d1bb0916"
     cluster="m3e9.6134b4a0d1bb0916"
     cluster_size="4"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="allaple rahack malicious"
     md5_hashes="['ada4bdd990a705b1d194cbc8e9e6b41b','b669267cb7cbb9e84bea8cfe151c07ec','e86240441a46559f81ddc4358c68607f']"

   strings:
      $hex_string = { 62fb7cf58e079811aa23a43db64fc059d26bec65fe7708811a9314ad26bf30c942db5cd56ee778f18a03841d962fa039b24bcc45de57e861fa73f48d069f10a9 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
