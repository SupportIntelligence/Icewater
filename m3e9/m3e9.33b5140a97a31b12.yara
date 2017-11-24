
rule m3e9_33b5140a97a31b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.33b5140a97a31b12"
     cluster="m3e9.33b5140a97a31b12"
     cluster_size="4"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit nimnul malicious"
     md5_hashes="['4a42baeaf63865968a54a8878458c266','588ab505314599276653bd797f6eda72','f8c024375d605ce49c471d1e85c3e712']"

   strings:
      $hex_string = { 7fc2866db052d717ee9d36c638ecd3da49b98b9107bdc8d82332d6988fccaf132875657039b1c95c4d69a5027b21b35487d0c7aaae0d0b1c5120be1bf989ab06 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
