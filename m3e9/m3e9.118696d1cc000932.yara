import "hash"

rule m3e9_118696d1cc000932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.118696d1cc000932"
     cluster="m3e9.118696d1cc000932"
     cluster_size="1741 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['77448cd728ff4e070081a895b193625d', '063af98ce3ed30a3a7830d3ad69271ef', '0330c470639a57562c329e99405b4643']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(36864,1024) == "be36e7d837001e86681445cdf3c7723f"
}

