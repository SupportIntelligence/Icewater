import "hash"

rule n3ed_53169cc1cc000b16
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3ed.53169cc1cc000b16"
     cluster="n3ed.53169cc1cc000b16"
     cluster_size="216 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="ramnit nimnul bmnup"
     md5_hashes="['de9bd2ba574dd4afda695a825078c4d5', 'd783deebfd85d3288fa688e9ede60c73', 'ac52940456c1bf5c43c3e12b243e54fc']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(138240,1536) == "c125b7c87b1684cc76c8a346e87e9126"
}

