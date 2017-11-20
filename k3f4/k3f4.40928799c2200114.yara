
rule k3f4_40928799c2200114
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3f4.40928799c2200114"
     cluster="k3f4.40928799c2200114"
     cluster_size="13"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171119"
     license = "RIL-1.0 [Rick's Internet License] "
     family="bladabindi backdoor malicious"
     md5_hashes="['3412229c35eda0da4fbce0da2c7405a2','6c187e36b1325a1d702047e7e07aede7','f27832088bb70ced442cc32730e64f0d']"

   strings:
      $hex_string = { 312e302e302e3022206e616d653d224d794170706c69636174696f6e2e617070222f3e0d0a20203c7472757374496e666f20786d6c6e733d2275726e3a736368 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
