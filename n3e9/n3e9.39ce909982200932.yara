import "hash"

rule n3e9_39ce909982200932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.39ce909982200932"
     cluster="n3e9.39ce909982200932"
     cluster_size="3 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="zusy cuegoe malicious"
     md5_hashes="['9f2668f19734821790b4c50663447293', '9f2668f19734821790b4c50663447293', '929aa11aea05a14b50aecaf6352633c0']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(457216,1071) == "230f2ca45f5ff1772009485514dc5a76"
}

