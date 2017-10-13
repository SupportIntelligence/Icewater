import "hash"

rule n3e9_31ca1369c8800932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.31ca1369c8800932"
     cluster="n3e9.31ca1369c8800932"
     cluster_size="16 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170831"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="zusy orbus malicious"
     md5_hashes="['cc18a0400556aea0f708d1670142092e', 'b7bccfe12c9791be16a1fe4548fb4bf9', 'a12ff27b0f3f3385dd0623d3e9e59bfb']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(411648,1024) == "08f7675b30b22ea37036af7df8d3f122"
}

