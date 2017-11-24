
rule m3e9_33954a52ea208916
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.33954a52ea208916"
     cluster="m3e9.33954a52ea208916"
     cluster_size="14"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="regrun ludbaruma emotet"
     md5_hashes="['0abd63362592490ad015c68606b5f473','26d39c78dcb23b601154384abd89d7b6','c959f4892cb8bc70817c2f6cafa261e6']"

   strings:
      $hex_string = { 1a288deb9841de2e9e96518f36305884a504c84943ce06d2d948730b2d29a2f6165a32459bbb40bc83b65ae11bb2941db4248e6771d47c8a770ee03cfc6644ea }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
