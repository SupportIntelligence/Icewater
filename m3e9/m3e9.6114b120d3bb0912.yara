
rule m3e9_6114b120d3bb0912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.6114b120d3bb0912"
     cluster="m3e9.6114b120d3bb0912"
     cluster_size="3"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="allaple rahack malicious"
     md5_hashes="['a7b8647a26b674b211e483b7d17c1c50','bd5644f793063e59a0434adc10bd5599','c0f0cb730d8102ea1638504e24ee403e']"

   strings:
      $hex_string = { 62fb7cf58e079811aa23a43db64fc059d26bec65fe7708811a9314ad26bf30c942db5cd56ee778f18a03841d962fa039b24bcc45de57e861fa73f48d069f10a9 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
