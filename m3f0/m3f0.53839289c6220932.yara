import "hash"

rule m3f0_53839289c6220932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3f0.53839289c6220932"
     cluster="m3f0.53839289c6220932"
     cluster_size="1050 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="razy gepys kryptik"
     md5_hashes="['b10ad9d851eb0121447a51e88580a604', 'af8ebd3c9902e61b56428a448bcc6709', 'b4b1cfa1186cb3d4d045dd9cffd4e100']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(123392,1024) == "750e8917afbd19751811b489e0ae951d"
}

