import "hash"

rule m3e9_5154ec869a986916
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.5154ec869a986916"
     cluster="m3e9.5154ec869a986916"
     cluster_size="49 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob virux"
     md5_hashes="['a9b84cbc12ec93096a12760b696a1a30', '42681308c45e3f78bbc780fda9d88b39', 'a0355c1bd94f9666a36ba339110840ae']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(182824,1064) == "9cf8ecfb1f9441dd702ff5d21ebd9bd9"
}

