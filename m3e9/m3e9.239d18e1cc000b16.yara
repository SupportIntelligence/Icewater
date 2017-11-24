
rule m3e9_239d18e1cc000b16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.239d18e1cc000b16"
     cluster="m3e9.239d18e1cc000b16"
     cluster_size="148"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="based remoteadmin winvnc"
     md5_hashes="['037ac74d62122f870dcded2944d662ce','03f40fe0e6776a5d5e0b48127211f435','1d92a92de0698486da45b55bfe3793d2']"

   strings:
      $hex_string = { 613fc0d10d41aea4f4d3e45adb4f9495d27b1d20628e2f175fe62aa135a847f2989222deb646544315ed9ac892793260fde91f529b107acc2c9f7f5d53b06bc6 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
