
rule k3e9_493e7134dda31916
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.493e7134dda31916"
     cluster="k3e9.493e7134dda31916"
     cluster_size="13"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171111"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virut virtob malicious"
     md5_hashes="['1330f4ecc0afb2ff489fee3fa87a34f8','2746bbf4c32a63cbfe42ad6c36b624b0','f078eceb008d160c9a1bfef1b0d58f37']"

   strings:
      $hex_string = { a8989000d8d0c80000000000a898900030005800d5ccc800c0c0c00048406000a084b800a8987800f5eacf0242004200d7a52f02a0a0a402ecd59d02ffffff02 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
