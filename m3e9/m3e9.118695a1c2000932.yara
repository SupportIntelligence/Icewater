import "hash"

rule m3e9_118695a1c2000932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.4 divinorum/0.992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.118695a1c2000932"
     cluster="m3e9.118695a1c2000932"
     cluster_size="46 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171031"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob virux"
     md5_hashes="['baf60d51279f863f086d0be568344dc1', 'd0bc1406b6efd5a85a30c7c26652bcea', 'c962e337b6a434693146c95e88360dbe']"


   condition:
      uint16(0) == 0x5A4D and 
      filesize > 65536 and filesize < 262144 and 
      hash.md5(36864,1024) == "be36e7d837001e86681445cdf3c7723f"
}

