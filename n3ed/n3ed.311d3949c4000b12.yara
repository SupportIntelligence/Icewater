import "hash"

rule n3ed_311d3949c4000b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3ed.311d3949c4000b12"
     cluster="n3ed.311d3949c4000b12"
     cluster_size="22 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="ramnit nimnul malicious"
     md5_hashes="['02fc6d9e228781ad967106a8e91144e1', '1383b393dd0fe0cc8c3fe99057a3ac48', 'da4ad6dd2e9e2b55820523333c6ff93a']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(53248,1024) == "2e1fd58e17e7ebd34f1ab92566daa558"
}

