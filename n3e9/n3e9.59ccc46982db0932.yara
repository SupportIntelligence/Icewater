import "hash"

rule n3e9_59ccc46982db0932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.59ccc46982db0932"
     cluster="n3e9.59ccc46982db0932"
     cluster_size="18 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob virux"
     md5_hashes="['827103d156a7506c42030c2f6bd53287', '2af3b13b408eb1a218d45bf2ec9c7973', '48cb310c903b73f0610f40da7de89e86']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(616730,1047) == "dd68d691dfcd761e2a378343685d10a8"
}

