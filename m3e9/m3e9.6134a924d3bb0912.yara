
rule m3e9_6134a924d3bb0912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.6134a924d3bb0912"
     cluster="m3e9.6134a924d3bb0912"
     cluster_size="8"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="allaple rahack malicious"
     md5_hashes="['0ca40a6afb8edb6616b8e83828c89668','637503de4eecd24d11cd02578e6c185c','e2ed11cdf00d04d15a51afdd4109937a']"

   strings:
      $hex_string = { a1559e712baf8157d4f0ce2cd626db46b08e227745e696507e1552b463d947aea569f9f88b73daac1a856628387c7837929958fa6002b1395fa70008408c4ad1 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
