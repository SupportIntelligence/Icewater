import "hash"

rule n3e9_5b156c4fee640932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.5b156c4fee640932"
     cluster="n3e9.5b156c4fee640932"
     cluster_size="438 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="nezchi ctfu filerepmalware"
     md5_hashes="['98d4d8448c5b229aabb2370374afed60', '10c320411c13176156d06494ae737314', '5ee941cf22b010034aee18a385a25311']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(317753,1025) == "e129b33318f7330bb957bd83ad81b55a"
}

