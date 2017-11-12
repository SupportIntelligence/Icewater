
rule n3e9_29171294dddb1912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.29171294dddb1912"
     cluster="n3e9.29171294dddb1912"
     cluster_size="106"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171111"
     license = "RIL-1.0 [Rick's Internet License] "
     family="kryptik malicious fxlt"
     md5_hashes="['00965d81892c9c71172fce09d815d123','011837829f70bed09a304ec47f7a1da2','1b2fa102b636b6ad5171cd467c603ab9']"

   strings:
      $hex_string = { 49602296f1e89c71b85f8498276d5129e4e3b03a7238c1d61ac74ee96b6f7ed8ce41f3ddacb6f8da950bf63cee7615010adb734c0300616a34f4638cfa86b733 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
