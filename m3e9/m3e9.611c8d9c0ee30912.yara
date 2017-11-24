
rule m3e9_611c8d9c0ee30912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.611c8d9c0ee30912"
     cluster="m3e9.611c8d9c0ee30912"
     cluster_size="141"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="vobfus sirefef diple"
     md5_hashes="['040001126678e075e16d30dd854932bb','05d5085cc1fd96734b199149a2c98347','4bec89f6a42f2cf05a15514e38af1172']"

   strings:
      $hex_string = { 459c506a02e80bd0feff83c40c8d4588506a00e885cffeffc38d4db8e800d0feffc38b45d88b4de064890d000000005f5e5bc9c21400558bec83ec1868a62f40 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
