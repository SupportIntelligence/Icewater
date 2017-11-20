
rule m3e9_3a5b11dcdaaaf310
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.3a5b11dcdaaaf310"
     cluster="m3e9.3a5b11dcdaaaf310"
     cluster_size="237"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="otwycal wapomi vjadtre"
     md5_hashes="['008334e9999d351a0d4541c5731b2e22','0162ffa2338caf1537f9cfa58150eb86','233aa9f57317eba95dffd8b1fdb8259f']"

   strings:
      $hex_string = { 82bc895d7e49860fd71f4a3043c137ef849a992c693bcf8bf8c3d1b2c4a8d94cc7152d3ca5643e3b28194f1a8eb013a9cef01d1787f4dccc46e050f3fcfe9be1 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
