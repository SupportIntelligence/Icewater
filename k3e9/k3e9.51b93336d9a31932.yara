import "hash"

rule k3e9_51b93336d9a31932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.51b93336d9a31932"
     cluster="k3e9.51b93336d9a31932"
     cluster_size="68 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['1f1a513d5b411b412c03bfc3a960ad38', '4ecd81fe8244fc02e344081c29fe457a', 'b985c7be3ae985305c2e5043a9467625']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(4096,1024) == "cf87fde8b009ce16dbc49360714f6a2f"
}

