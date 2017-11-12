
rule m3e9_2313a1e8c2800912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.2313a1e8c2800912"
     cluster="m3e9.2313a1e8c2800912"
     cluster_size="10"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171111"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virut virtob malicious"
     md5_hashes="['2238fc90e915cf0fae807fd2591e82fc','2d6b61afbbab76d921a04ad396cc0acb','dc1f319c2f742b919790ff974d97596d']"

   strings:
      $hex_string = { d9c1e902756c8807474b75fa5b5e8b4424085fc3891783c7044974afbafffefe7e8b0603d083f0ff33c28b1683c604a90001018174de84d2742c84f6741ef7c2 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
