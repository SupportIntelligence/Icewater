import "hash"

rule m3ed_4b958d1f64964692
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3ed.4b958d1f64964692"
     cluster="m3ed.4b958d1f64964692"
     cluster_size="150 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="ramnit nimnul bmnup"
     md5_hashes="['cf83c42653235505cf4b656cb9fe5aa0', 'dba4b83f701ca5c5a73cf687cd268a32', 'd11af45501b84a432b24fe530345368c']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(156672,1536) == "0f4c07f5fc878e2aa1805fefc0c25f7a"
}

