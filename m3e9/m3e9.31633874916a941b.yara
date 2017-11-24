
rule m3e9_31633874916a941b
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.31633874916a941b"
     cluster="m3e9.31633874916a941b"
     cluster_size="4"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="qvod viking jadtre"
     md5_hashes="['a43c5cc7ed9dafa2db216a1056f99b13','b6ee0dd10bd3f5ce30be7d3c82dfb555','c9877fe93b7f89f8e4e748595fab69cb']"

   strings:
      $hex_string = { 49112e5a48e305b27e8aab1b264554b51a3088e66d8dbe8694779b125feac320737f5ba94b5e61f693af6c3d69cbfa773efdf527faf7928715959e5689ba556f }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
