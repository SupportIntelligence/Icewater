
rule k3ec_0914ca8982220b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3ec.0914ca8982220b12"
     cluster="k3ec.0914ca8982220b12"
     cluster_size="7"
     filetype = "PE32 executable (console) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171121"
     license = "RIL-1.0 [Rick's Internet License] "
     family="brontok email pazetus"
     md5_hashes="['433ce8eb6907b1715256688aca4475e0','4bcd96e76c49a67fac208b466b56d17e','f56ce1d729283256b757ebb518f2b411']"

   strings:
      $hex_string = { cdf190ab4a71bc2550d1da4d9f54d353ecd2790e9bcee188e53ce2603b7855f32a68866207f213273641a3b9521c9e1d78be2c805ad865aec7095d902d895bcc }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
