
rule m3e9_331db099c2200b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.331db099c2200b12"
     cluster="m3e9.331db099c2200b12"
     cluster_size="4"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171121"
     license = "RIL-1.0 [Rick's Internet License] "
     family="otwycal wapomi vjadtre"
     md5_hashes="['09941266e423f7755df5c1ae0ce37fc8','993cef97eda994a5b47cb6c892821593','e120ccef5333487b98fc1a8d9ba11bcc']"

   strings:
      $hex_string = { 9827d4c6a8a2492ddfe1ad792207fe7e467fdad09f1fe84f2b8767688f4ee563593324e77ac8052aac3093d70a54f32cff43adab3c85b884322e6af9cea1aa03 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
