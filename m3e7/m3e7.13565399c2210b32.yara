
rule m3e7_13565399c2210b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e7.13565399c2210b32"
     cluster="m3e7.13565399c2210b32"
     cluster_size="7"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="regrun ludbaruma bruhorn"
     md5_hashes="['030170b17b9175651f095c253cbdef91','3315b3bd550c78accfa18d11a87b73ad','d71689003dda8a5f64187a7bba67d0cc']"

   strings:
      $hex_string = { b0895da0895d90750f683459420068f4664000e86b9ffeff8b35345942008d4de051568b06ff50143bc3dbe27d11bfc06840006a14575650e8409ffeffeb05bf }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
