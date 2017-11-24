
rule k3e9_09259862d9eb1912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.09259862d9eb1912"
     cluster="k3e9.09259862d9eb1912"
     cluster_size="4"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="vobfus symmi vbkrypt"
     md5_hashes="['0e0cc6cf424bb67efe67339bcf736c39','0e4678afefe6d0d2859072d22585b1dc','b695bf7ff83ee929c6872d0aa428ff65']"

   strings:
      $hex_string = { c96a5445aed09193d1bed9688fecdd783b1cbbf68774971417eaf5a80023d3e63a3a32b5eed694021875b76ce1f2cf9b53487c5aaf86b679dd27357dc2476415 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
